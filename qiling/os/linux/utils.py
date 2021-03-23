#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
set_tls
"""
def ql_arm_init_get_tls(ql):
    ql.mem.map(0xFFFF0000, 0x1000, info="[arm_tls]")
    """
    'adr r0, data; ldr r0, [r0]; mov pc, lr; data:.ascii "\x00\x00"'
    """
    sc = b'\x04\x00\x8f\xe2\x00\x00\x90\xe5\x0e\xf0\xa0\xe1\x00\x00\x00\x00'

    # if ql.archendian == QL_ENDIAN.EB:
    #    sc = swap_endianess(sc)

    ql.mem.write(ql.arch.arm_get_tls_addr, sc)
    ql.log.debug("Set init_kernel_get_tls")    

def swap_endianess(s: bytes, blksize=4) -> bytes:
    blocks = (s[i:i + blksize] for i in range(0, len(s), blksize))

    return b''.join(bytes(reversed(b)) for b in blocks)
