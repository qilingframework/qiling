#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

import struct
from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *

from qiling.utils import *
from qiling.arch.filetype import *
from qiling.exception import *


def ql_addr_to_str(ql, addr, short, endian):
    if ql.archbit == 64 and short == False:
        addr = (hex(int.from_bytes(struct.pack('<Q', addr), byteorder=endian)))
        addr = '{:0>16}'.format(addr[2:])
    elif ql.archbit == 32 or short == True:
        addr = (hex(int.from_bytes(struct.pack('<I', addr), byteorder=endian)))
        addr = ('{:0>8}'.format(addr[2:]))
    addr = str(addr)    
    return addr

def ql_get_reg_spc(ql):
    if ql.arch == QL_X86:
        get_reg_pc, get_reg_sp = UC_X86_REG_EIP, UC_X86_REG_SP
    elif ql.arch == QL_X8664:
        get_reg_pc, get_reg_sp = UC_X86_REG_RIP, UC_X86_REG_RSP
    elif ql.arch == QL_ARM:
        get_reg_pc, get_reg_sp = UC_ARM_REG_PC, UC_ARM_REG_SP
    elif ql.arch == QL_ARM_THUMB:
        get_reg_pc, get_reg_sp = UC_ARM_REG_PC, UC_ARM_REG_SP
    #elif ql.arch == QL_ARM64:
    #    return UC_ARM64_REG_PC
    #elif ql.arch == QL_MIPS32EL:
    #    return UC_MIPS_REG_PC  
    return get_reg_pc, get_reg_sp   