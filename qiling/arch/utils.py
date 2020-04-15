#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that are only used in qiling.arch
"""

import struct

def ql_addr_to_str(ql, addr, short=False, endian="big"):
    if ql.archbit == 64 and short == False:
        addr = (hex(int.from_bytes(struct.pack('<Q', addr), byteorder=endian)))
        addr = '{:0>16}'.format(addr[2:])
    elif ql.archbit == 32 or short == True:
        addr = (hex(int.from_bytes(struct.pack('<I', addr), byteorder=endian)))
        addr = ('{:0>8}'.format(addr[2:]))
    addr = str(addr)    
    return addr
    

