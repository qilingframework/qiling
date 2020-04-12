#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.arm_const import *
from unicorn.mips_const import *

from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.linux.const import *
from qiling.exception import *
from qiling.os.const import *
from qiling.os.utils import *


"""
common utils 
"""
def ql_map_shellcode(ql, start, shellcode, shellcode_addr, shellcode_addr_size):
    if ql.shellcode_init == 0:
        ql.mem.map(shellcode_addr, shellcode_addr_size)
        ql.shellcode_init = 1
    ql.mem.write(shellcode_addr + start, shellcode)

"""
set_tls
"""
def ql_arm_init_kernel_get_tls(ql):
    ql.mem.map(0xFFFF0000, 0x1000)
    """
    'adr r0, data; ldr r0, [r0]; mov pc, lr; data:.ascii "\x00\x00"'
    """
    sc = b'\x04\x00\x8f\xe2\x00\x00\x90\xe5\x0e\xf0\xa0\xe1\x00\x00\x00\x00'

    # if ql.archendian == QL_ENDIAN_EB:
    #    sc = ql_lsbmsb_convert(ql, sc)

    ql.mem.write(QL_ARM_KERNEL_GET_TLS_ADDR, sc)
    ql.dprint(D_INFO, "[+] Set init_kernel_get_tls")    
         