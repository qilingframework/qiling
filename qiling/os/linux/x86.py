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
from qiling.os.linux.x86_syscall import *
from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.utils import *
from qiling.os.linux.thread import *
from qiling.arch.filetype import *

QL_X86_LINUX_PREDEFINE_STACKADDRESS = 0xfffdd000
QL_X86_LINUX_PREDEFINE_STACKSIZE = 0x21000

QL_X86_EMU_END = 0x8fffffff


def hook_syscall(ql, intno):
    syscall_num  = ql.uc.reg_read(UC_X86_REG_EAX)
    param0 = ql.uc.reg_read(UC_X86_REG_EBX)
    param1 = ql.uc.reg_read(UC_X86_REG_ECX)
    param2 = ql.uc.reg_read(UC_X86_REG_EDX)
    param3 = ql.uc.reg_read(UC_X86_REG_ESI)
    param4 = ql.uc.reg_read(UC_X86_REG_EDI)
    param5 = ql.uc.reg_read(UC_X86_REG_EBP)
    pc = ql.uc.reg_read(UC_X86_REG_EIP)

    linux_syscall_numb_list = []
    linux_syscall_func_list = []

    for i in X86_LINUX_SYSCALL:
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

            td = ql.thread_management.cur_thread
            td.stop()
            td.stop_event = THREAD_EVENT_UNEXECPT_EVENT

            if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                if ql.debug_stop:
                    ql.uc.emu_stop()
                raise
    else:
        ql.nprint("0x%x: syscall number = 0x%x(%d) not implement." %(pc, syscall_num, syscall_num))
        if ql.debug_stop:
            ql.uc.emu_stop()

        td = ql.thread_management.cur_thread
        td.stop()
        td.stop_event = THREAD_EVENT_UNEXECPT_EVENT


def ql_x86_thread_set_tls(ql, th, arg):
    u_info = arg
    # u_info = ql.uc.mem_read(u_info_addr, 4 * 3)
    base = ql.unpack32(u_info[4 : 8])
    limit = ql.unpack32(u_info[8 : 12])
    ql_x86_setup_syscall_set_thread_area(ql, base, limit)
    

def ql_x86_syscall_set_thread_area(ql, u_info_addr, null0, null1, null2, null3, null4):
    ql.nprint("set_thread_area(u_info_addr= 0x%x)" % u_info_addr)
    u_info = ql.uc.mem_read(u_info_addr, 4 * 3)

    ql.thread_management.cur_thread.set_special_settings_arg(u_info)

    base = ql.unpack32(u_info[4 : 8])
    limit = ql.unpack32(u_info[8 : 12])
    ql.nprint("[+] set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))
    ql_x86_setup_syscall_set_thread_area(ql, base, limit)
    ql.uc.mem_write(u_info_addr, ql.pack32(12))
    regreturn = 0
    ql_definesyscall_return(ql, regreturn)


def loader_file(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = QL_X86_LINUX_PREDEFINE_STACKADDRESS
        ql.stack_size = QL_X86_LINUX_PREDEFINE_STACKSIZE
        uc.mem_map(ql.stack_address, ql.stack_size)
    loader = ELFLoader(ql.path, ql)
    if loader.load_with_ld(ql, ql.stack_address + ql.stack_size, argv = ql.argv,  env = ql.env):
        raise QlErrorFileType("Unsupported FileType")
    ql.stack_address = (int(ql.new_stack))
    

def loader_shellcode(ql):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    ql.uc = uc
    if (ql.stack_address == 0):
        ql.stack_address = 0x1000000
        ql.stack_size = 2 * 1024 * 1024
        uc.mem_map(ql.stack_address,  ql.stack_size)
    ql.stack_address =  ql.stack_address  + 0x100000
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
            thread_management = ThreadManagement(ql)
            ql.thread_management = thread_management

            main_thread = Thread(ql, thread_management, total_time = ql.timeout, special_settings_fuc = ql_x86_thread_set_tls)
            main_thread.save()
            main_thread.set_start_address(ql.entry_point)

            thread_management.set_main_thread(main_thread)
            thread_management.run()

    except UcError as e:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            ql.nprint("[+] PC= " + hex(ql.pc))
            ql.show_map_info()
            buf = ql.uc.mem_read(ql.pc, 8)
            ql.nprint("[+] ", [hex(_) for _ in buf])
            ql.nprint("\n")
            ql_hook_code_disasm(ql, 64)
        ql.errmsg = 1
        ql.nprint("%s" % e)
        raise QlErrorExecutionStop('[!] Emulation Stopped')

    if ql.internal_exception != None:
        raise ql.internal_exception
