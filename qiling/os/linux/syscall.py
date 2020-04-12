#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
#  
import struct
import sys
import os
import string
import resource
import socket
import time
import io
import select

from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *
from qiling.arch.x86 import *
from qiling.os.linux.const import *
from qiling.os.linux.utils import *
from qiling.os.utils import *
from qiling.const import *
from qiling.os.posix.syscall import *


def ql_x8664_syscall_clone(ql, clone_flags, clone_child_stack, clone_parent_tidptr, clone_child_tidptr, clone_newtls, *args, **kw):
    ql_syscall_clone(ql, clone_flags, clone_child_stack, clone_parent_tidptr, clone_newtls, clone_child_tidptr, *args, **kw)


def ql_x86_syscall_set_thread_area(ql, u_info_addr, *args, **kw):
    GDT_ENTRY_TLS_MIN = 12
    GDT_ENTRY_TLS_MAX = 14

    ql.nprint("set_thread_area(u_info_addr= 0x%x)" % u_info_addr)

    u_info = ql.mem.read(u_info_addr, 4 * 4)
    index = ql.unpack32s(u_info[0 : 4])
    base = ql.unpack32(u_info[4 : 8])
    limit = ql.unpack32(u_info[8 : 12])

    ql.dprint(D_INFO, "[+] set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))

    if index == -1:
        index = ql.os.gdtm.get_free_idx(12)

    if index == -1 or index < 12 or index > 14:
        regreturn = -1 
    else:
        ql.os.gdtm.register_gdt_segment(index, base, limit, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3)
        ql.mem.write(u_info_addr, ql.pack32(index))
        regreturn = 0
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_mips32_set_thread_area(ql, sta_area, *args, **kw):
    ql.nprint ("set_thread_area(0x%x)" % sta_area)

    if ql.thread_management != None and ql.multithread == True:
        ql.thread_management.cur_thread.special_settings_arg = sta_area
    
    CONFIG3_ULR = (1 << 13)
    ql.register(UC_MIPS_REG_CP0_CONFIG3, CONFIG3_ULR)
    ql.register(UC_MIPS_REG_CP0_USERLOCAL, sta_area)
    ql.register(UC_MIPS_REG_V0, 0)
    ql.register(UC_MIPS_REG_A3, 0)


def ql_syscall_arm_settls(ql, address, *args, **kw):
    #ql.nprint("settls(0x%x)" % address)
    
    if ql.thread_management != None and ql.multithread == True:
        ql.thread_management.cur_thread.special_settings_arg = address

    ql.register(UC_ARM_REG_C13_C0_3, address)
    ql.mem.write(QL_ARM_KERNEL_GET_TLS_ADDR + 12, ql.pack32(address))
    ql.register(UC_ARM_REG_R0, address)
    ql.nprint("settls(0x%x)" % address)
