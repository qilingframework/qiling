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


def ql_x86_syscall_set_thread_area(ql, u_info_addr, *args, **kw):
    ql.nprint("set_thread_area(u_info_addr= 0x%x)" % u_info_addr)
    u_info = ql.mem.read(u_info_addr, 4 * 3)

    if ql.thread_management != None and ql.multithread == True:
        ql.thread_management.cur_thread.set_special_settings_arg(u_info)

    base = ql.unpack32(u_info[4 : 8])
    limit = ql.unpack32(u_info[8 : 12])

    ql.dprint(0, "[+] set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))
    ql_x86_setup_syscall_set_thread_area(ql, base, limit)
    ql.mem.write(u_info_addr, ql.pack32(12))
    regreturn = 0
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_mips32_set_thread_area(ql, sta_area, *args, **kw):
    from qiling.os.linux.utils import exec_shellcode
    ql.nprint ("set_thread_area(0x%x)" % sta_area)

    if ql.thread_management != None and ql.multithread == True:
        ql.thread_management.cur_thread.special_settings_arg = sta_area
    
    CONFIG3_ULR = (1 << 13)
    ql.register(UC_MIPS_REG_CP0_CONFIG3, CONFIG3_ULR)
    ql.register(UC_MIPS_REG_CP0_USERLOCAL, sta_area)

    if ql.archendian == QL_ENDIAN_EB:
        exec_shellcode(ql, ql.pc + 4, bytes.fromhex('0000102500003825'))
    else:    
        exec_shellcode(ql, ql.pc + 4, bytes.fromhex('2510000025380000'))


def ql_syscall_arm_settls(ql, address, *args, **kw):
    #ql.nprint("settls(0x%x)" % address)
    
    if ql.thread_management != None and ql.multithread == True:
        ql.thread_management.cur_thread.special_settings_arg = address

    mode = ql.arch.check_thumb()
    if mode == UC_MODE_THUMB:
        sc = '''
            .THUMB
             _start:
                push {r1}
                adr r1, main
                bx r1

            .code 32
            main:
                mcr p15, 0, r0, c13, c0, 3
                adr r1, ret_to
                add r1, r1, #1
                bx r1
            .THUMB
            ret_to:
                pop {r1}
                pop {pc}
            '''
        sc = b'\x02\xb4\x01\xa1\x08G\x00\x00p\x0f\r\xee\x04\x10\x8f\xe2\x01\x10\x81\xe2\x11\xff/\xe1\x02\xbc\x00\xbd'
        # if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc, 2)
    else:
        sc = b'p\x0f\r\xee\x04\xf0\x9d\xe4'
        # if ql.archendian == QL_ENDIAN_EB:
        #    sc = ql_lsbmsb_convert(ql, sc)

    codestart = 4
    ql_map_shellcode(ql, codestart, sc, QL_ARCHBIT32_SHELLCODE_ADDR, QL_ARCHBIT32_SHELLCODE_SIZE)
    codelen = 0
    if mode == UC_MODE_THUMB:
        codelen = 1
    
    ql.mem.write(ql.sp - 4, ql.pack32(ql.pc))
    ql.register(UC_ARM_REG_SP, ql.sp - 4)
    ql.register(UC_ARM_REG_PC, QL_SHELLCODE_ADDR + codestart + codelen)

    ql.mem.write(QL_ARM_KERNEL_GET_TLS_ADDR + 12, ql.pack32(address))
    ql.register(UC_ARM_REG_R0, address)
    ql.nprint("settls(0x%x)" % address)
