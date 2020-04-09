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
from qiling.const import *
from qiling.exception import *


def ql_arch_setup(ql):
    if not ql_is_valid_arch(ql.archtype):
        raise QlErrorArch("[!] Invalid Arch")
    
    archmanager = ql_arch_convert_str(ql.archtype).upper()
    archmanager = ("QlArch" + archmanager)

    module_name = ql_build_module_import_name("arch", None, ql.archtype)
    return ql_get_module_function(module_name, archmanager)(ql)
    

def ql_addr_to_str(ql, addr, short, endian):
    if ql.archbit == 64 and short == False:
        addr = (hex(int.from_bytes(struct.pack('<Q', addr), byteorder=endian)))
        addr = '{:0>16}'.format(addr[2:])
    elif ql.archbit == 32 or short == True:
        addr = (hex(int.from_bytes(struct.pack('<I', addr), byteorder=endian)))
        addr = ('{:0>8}'.format(addr[2:]))
    addr = str(addr)    
    return addr
    

