#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

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
from qiling.os.macos.x8664_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.macos.syscall import *
from qiling.os.macos.utils import *
from qiling.os.utils import *
from qiling.arch.filetype import *


QL_X8664_MACOS_PREDEFINE_STACKADDRESS = 0x7fffff500000
QL_X8664_MACOS_PREDEFINE_STACKSIZE = 0xa00000
QL_X8664_MACOS_PREDEFINE_MMAPADDRESS = 0x7fffff000000

QL_X8664_EMU_END = 0xffffffffffffffff


def hook_syscall(ql):
    syscall_num  = ql.uc.reg_read(UC_X86_REG_RAX)
    param0 = ql.uc.reg_read(UC_X86_REG_RDI)
    param1 = ql.uc.reg_read(UC_X86_REG_RSI)
    param2 = ql.uc.reg_read(UC_X86_REG_RDX)
    param3 = ql.uc.reg_read(UC_X86_REG_R10)
    param4 = ql.uc.reg_read(UC_X86_REG_R8)
    param5 = ql.uc.reg_read(UC_X86_REG_R9)
    pc = ql.uc.reg_read(UC_X86_REG_RIP)

    macos_syscall_numb_list = []
    macos_syscall_func_list = []

    for i in X8664_MACOS_SYSCALL:
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
        ql.nprint("0x%x: syscall number = 0x%x(%d) not implement." %(pc, syscall_num,  (syscall_num -  0x2000000)))
        if ql.debug_stop:
            ql.uc.emu_stop()


def loader_file(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    ql.mmap_start = QL_X8664_MACOS_PREDEFINE_MMAPADDRESS
    if (ql.stack_address == 0):
        ql.stack_address = QL_X8664_MACOS_PREDEFINE_STACKADDRESS
        ql.stack_size = QL_X8664_MACOS_PREDEFINE_STACKSIZE
        uc.mem_map(ql.stack_address, ql.stack_size)
        stack_esp = QL_X8664_MACOS_PREDEFINE_STACKADDRESS + QL_X8664_MACOS_PREDEFINE_STACKSIZE
    envs = env_dict_to_array(ql.env)
    # loader = MachoX8664(ql, ql.path, stack_esp, [ql.path], envs, "/bin/x8664_hello", 1)
    apples = ql_real_to_vm_abspath(ql, ql.path)
    loader = MachoX8664(ql, ql.path, stack_esp, [ql.path], envs, apples, 1)
    loader.loadMachoX8664()
    ql.stack_address = (int(ql.stack_esp))
    

def loader_shellcode(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
        ql.stack_size = 2 * 1024 * 1024
        uc.mem_map(ql.stack_address,  ql.stack_size)
    ql.stack_address = ql.stack_address  + 0x200000 - 0x1000
    ql.uc.mem_write(ql.stack_address, ql.shellcoder)
    

def runner(ql):
    ql.debug_stop = True
    ql.uc.reg_write(UC_X86_REG_RSP, ql.stack_address)
    ql_setup(ql)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)
    ql_x8664_setup_gdt_segment_ds(ql)
    ql_x8664_setup_gdt_segment_cs(ql)
    ql_x8664_setup_gdt_segment_ss(ql)

    if (ql.until_addr == 0):
        ql.until_addr = QL_X8664_EMU_END
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


