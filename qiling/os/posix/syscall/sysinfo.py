#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_sysinfo(ql: Qiling, info: int):
    # TODO: the packing method for 'long' fields is set to ql.pack even though
    # it is unclear whether it should match pointersize or be 64 bits anyway

    fields = (
        (0x0000000000001234, ql.pack),   # uptime
        (0x0000000000002000, ql.pack),   # loads (1 min)
        (0x0000000000002000, ql.pack),   # loads (5 min)
        (0x0000000000002000, ql.pack),   # loads (15 min)
        (0x0000000010000000, ql.pack),   # total ram
        (0x0000000010000000, ql.pack),   # free ram
        (0x0000000010000000, ql.pack),   # shared memory
        (0x0000000000000000, ql.pack),   # memory used by buffers
        (0x0000000000000000, ql.pack),   # total swap
        (0x0000000000000000, ql.pack),   # free swap
        (0x0001,             ql.pack16), # nb current processes
        (0x0000000000000000, ql.pack),   # total high mem
        (0x0000000000000000, ql.pack),   # available high mem
        (0x00000000,         ql.pack32)  # memory unit size
    )

    data = b''.join(pmethod(val) for val, pmethod in fields)

    ql.mem.write(info, data.ljust(64, b'\x00'))

    return 0
