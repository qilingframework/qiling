#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_uname(ql: Qiling, buf: int):
    UTSLEN = 65

    fields = (
        b'QilingOS',                 # sysname
        b'ql_vm',                    # nodename
        b'99.0-RELEASE',             # release
        b'QilingOS 99.0-RELEASE r1', # version
        b'ql_processor',             # machine
        b''                          # domainname
    )

    for i, f in enumerate(fields):
        ql.mem.write(buf + i * UTSLEN, f.ljust(UTSLEN, b'\x00'))

    return 0
