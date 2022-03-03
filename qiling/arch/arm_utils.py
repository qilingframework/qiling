#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def init_get_tls(ql: Qiling, address: int) -> None:
    # adr   r0, data
    # ldr   r0, [r0]
    # mov   pc, lr
    #
    # data:
    #   .ascii "\x00\x00"

    code = bytes.fromhex('''
        04 00 8f e2
        00 00 90 e5
        0e f0 a0 e1
        00 00 00 00
    ''')

    # if endian == QL_ENDIAN.EB:
    #    code = swap_endianess(code)

    base = ql.mem.align(address)
    size = ql.mem.align_up(len(code))

    ql.mem.map(base, size, info="[arm_tls]")
    ql.mem.write(address, code)

    ql.log.debug('Set kernel get_tls')

# def swap_endianess(s: bytes, blksize: int = 4) -> bytes:
#     blocks = (s[i:i + blksize] for i in range(0, len(s), blksize))
#
#     return b''.join(bytes(reversed(b)) for b in blocks)