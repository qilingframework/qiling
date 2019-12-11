#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
import sys

from unicorn import *
from unicorn.arm64_const import *

from capstone import *
from capstone.arm64_const import *

from keystone import *
from keystone.arm64_const import *

from struct import pack
import os

import string

from qiling.loader.elf import *
from qiling.os.linux.arm64_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.utils import *
from qiling.arch.filetype import *

QL_ARM64_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
QL_ARM64_LINUX_PREDEFINE_STACKSIZE = 0x21000

QL_ARM64_EMU_END = 0xffffffffffffffff

linux_syscall_numb_list = []
linux_syscall_func_list = []

def init_syscall_table(ql):
    for i in ARM64_LINUX_SYSCALL:
        linux_syscall_numb_list.append(i[0])
        linux_syscall_func_list.append(i[1])

def hook_syscall(ql, intno):
    syscall_num  = ql.uc.reg_read(UC_ARM64_REG_X8)
    param0 = ql.uc.reg_read(UC_ARM64_REG_X0)
    param1 = ql.uc.reg_read(UC_ARM64_REG_X1)
    param2 = ql.uc.reg_read(UC_ARM64_REG_X2)
    param3 = ql.uc.reg_read(UC_ARM64_REG_X3)
    param4 = ql.uc.reg_read(UC_ARM64_REG_X4)
    param5 = ql.uc.reg_read(UC_ARM64_REG_X5)
    pc = ql.uc.reg_read(UC_ARM64_REG_PC)


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


def ql_arm64_enable_vfp(uc):
    ARM64FP = uc.reg_read(UC_ARM64_REG_CPACR_EL1)
    ARM64FP |= 0x300000
    uc.reg_write(UC_ARM64_REG_CPACR_EL1, ARM64FP)


def loader_file(ql):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = QL_ARM64_LINUX_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0):  
        ql.stack_size = QL_ARM64_LINUX_PREDEFINE_STACKSIZE
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv,  env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address = (int(ql.new_stack))


def loader_shellcode(ql):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ql.uc = uc

    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0): 
        ql.stack_size = 2 * 1024 * 1024
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    ql.stack_address =  ql.stack_address  + 0x200000 - 0x1000    
    ql.uc.mem_write(ql.stack_address, ql.shellcoder) 

def runner(ql):
    ql.uc.reg_write(UC_ARM64_REG_SP, ql.stack_address)
    ql_setup(ql)
    init_syscall_table(ql)
    ql.hook_intr(hook_syscall)
    ql_arm64_enable_vfp(ql.uc)
    if (ql.until_addr == 0):
        ql.until_addr = QL_ARM64_EMU_END
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
        raise QlErrorExecutionStop('[!] Emulation Stopped due to %s' %(e))

    if ql.internal_exception != None:
        raise ql.internal_exception
