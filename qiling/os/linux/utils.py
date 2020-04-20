#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .const import *
from qiling.const import *

"""
set_tls
"""
def ql_arm_init_kernel_get_tls(ql):
    ql.mem.map(0xFFFF0000, 0x1000, info="[arm_tls]")
    """
    'adr r0, data; ldr r0, [r0]; mov pc, lr; data:.ascii "\x00\x00"'
    """
    sc = b'\x04\x00\x8f\xe2\x00\x00\x90\xe5\x0e\xf0\xa0\xe1\x00\x00\x00\x00'

    # if ql.archendian == QL_ENDIAN.EB:
    #    sc = ql.os.lsbmsb_convert(ql, sc)

    ql.mem.write(ql.os.QL_ARM_KERNEL_GET_TLS_ADDR, sc)
    ql.dprint(D_INFO, "[+] Set init_kernel_get_tls")    
         