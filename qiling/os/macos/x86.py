#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
import sys

from unicorn import *
from unicorn.x86_const import *

from capstone import *
from capstone.x86_const import *

from keystone import *
from keystone.x86_const import *

from struct import pack
import os

import string

from qiling.loader.macho import *
from qiling.arch.x86 import *
from qiling.os.macos.x86_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.macos.syscall import *
from qiling.os.macos.utils import *
from qiling.os.utils import *
from qiling.arch.filetype import *

QL_X86_MACOS_PREDEFINE_STACKADDRESS = 0xfffdd000
QL_X86_MACOS_PREDEFINE_STACKSIZE = 0x21000

QL_X86_EMU_END = 0x8fffffff


def hook_syscall(ql, intno):
    syscall_num  = ql.uc.reg_read(UC_X86_REG_EAX)
    param0 = ql.uc.reg_read(UC_X86_REG_EAX)
    param0 = ql.stack_read(4 * 1)
    param1 = ql.stack_read(4 * 2)
    param2 = ql.stack_read(4 * 3)
    param3 = ql.stack_read(4 * 4)
    param4 = ql.stack_read(4 * 5)
    param5 = ql.stack_read(4 * 6)
    pc = ql.uc.reg_read(UC_X86_REG_RIP)

    if intno not in (0x80, 0x81, 0x82):
        ql.nprint("got interrupt 0x%x ???" %intno)
        return

    if intno == 0x81:
        syscall_num = syscall_num + 0x8100

    elif intno == 0x82:
        syscall_num = syscall_num + 0x8200

    macos_syscall_numb_list = []
    macos_syscall_func_list = []

    for i in X86_MACOS_SYSCALL:
        macos_syscall_numb_list.append(i[0])
        macos_syscall_func_list.append(i[1])

    if any(macos_syscall_numb == syscall_num for macos_syscall_numb in macos_syscall_numb_list):
        macos_syscall_index = macos_syscall_numb_list.index(syscall_num)
        MACOS_SYSCALL_FUNC = eval(macos_syscall_func_list[macos_syscall_index])
        try:
            MACOS_SYSCALL_FUNC(ql, param0, param1, param2, param3, param4, param5)
        except:
            ql.errmsg = 1
            ql.nprint("SYSCALL: ", macos_syscall_func_list[macos_syscall_index])
            if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                if ql.debug_stop:
                    ql.uc.emu_stop()
                raise
    else:
        ql.nprint("0x%x: syscall number = 0x%x(%d) not implement" %(pc, syscall_num, syscall_num))
        if ql.debug_stop:
            ql.uc.emu_stop()


def loader_file(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    ql.uc = uc
    ql.mmap_start = 0xd0000000
    if (ql.stack_address == 0):
        ql.stack_address = QL_X86_MACOS_PREDEFINE_STACKADDRESS
    if (ql.stack_size == 0): 
        ql.stack_size = QL_X86_MACOS_PREDEFINE_STACKSIZE
    ql.uc.mem_map(ql.stack_address, ql.stack_size)
    stack_esp = QL_X86_MACOS_PREDEFINE_STACKADDRESS + QL_X86_MACOS_PREDEFINE_STACKSIZE
    envs = env_dict_to_array(ql.env)
    loader = MachoX86(ql, ql.path, stack_esp, [ql.path], envs, [ql.path], 1)
    loader.loadMachoX86()
    ql.stack_address = (int(ql.stack_esp))


def loader_shellcode(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
    if (ql.stack_size == 0): 
        ql.stack_size = 2 * 1024 * 1024
    ql.uc.mem_map(ql.stack_address,  ql.stack_size)
    ql.stack_address= ql.stack_address  + 0x200000 - 0x1000
    ql.uc.mem_write(ql.stack_address, ql.shellcoder)
    

def runner(ql):
    ql.uc.reg_write(UC_X86_REG_ESP, ql.stack_address) 
    ql_setup(ql)
    ql.hook_intr(hook_syscall)
    ql_x86_setup_gdt_segment_ds(ql)
    ql_x86_setup_gdt_segment_cs(ql)
    ql_x86_setup_gdt_segment_ss(ql)

    if (ql.until_addr == 0):
        ql.until_addr = QL_X86_EMU_END
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
        ql.errmsg = 1
        ql.nprint("%s" % e)
        raise QlErrorExecutionStop('[!] Emulation Stopped')  


