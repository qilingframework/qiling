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

from qiling.loader.elf import *
from qiling.arch.x86 import *
from qiling.os.linux.x8664_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.utils import *
from qiling.arch.filetype import *


QL_X8664_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
QL_X8664_LINUX_PREDEFINE_STACKSIZE = 0x21000

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

    linux_syscall_numb_list = []
    linux_syscall_func_list = []

    for i in X8664_LINUX_SYSCALL:
        linux_syscall_numb_list.append(i[0])
        linux_syscall_func_list.append(i[1])

    if any(linux_syscall_numb == syscall_num for linux_syscall_numb in linux_syscall_numb_list):
        linux_syscall_index = linux_syscall_numb_list.index(syscall_num)
        LINUX_SYSCALL_FUNC= eval(linux_syscall_func_list[linux_syscall_index])
        try:
            LINUX_SYSCALL_FUNC(ql, param0, param1, param2, param3, param4, param5)
        except KeyboardInterrupt:
            raise
        except:
            ql.errmsg = 1
            ql.nprint("SYSCALL: ", linux_syscall_func_list[linux_syscall_index])
            
            if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                if ql.debug_stop:
                    ql.uc.emu_stop()
                raise
    else:
        ql.nprint("0x%x: syscall number = 0x%x(%d) not implement." %(pc, syscall_num, syscall_num))
        if ql.debug_stop:
            ql.uc.emu_stop()


def loader_file(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = QL_X8664_LINUX_PREDEFINE_STACKADDRESS
        ql.stack_size = QL_X8664_LINUX_PREDEFINE_STACKSIZE
        uc.mem_map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv,  env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address = (int(ql.new_stack))
    

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
    ql.uc.reg_write(UC_X86_REG_RSP, ql.stack_address)
    ql_setup(ql)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)
    if not ql.shellcoder: 
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
        raise QlErrorExecutionStop('[!] Emulation Stopped')    


    if ql.internal_exception != None:
        raise ql.internal_exception
