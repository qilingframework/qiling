#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS

def ql_syscall_uname(ql: Qiling, buf: int):
    UTSLEN = 65

    # Linux reports RV64 guests as "riscv64" in utsname.machine.
    if ql.os.type == QL_OS.LINUX and ql.arch.type == QL_ARCH.RISCV64:
        machine = b'riscv64'
    else:
        machine = b'ql_processor'

    fields = (
        b'QilingOS',                 # sysname
        b'ql_vm',                    # nodename
        b'99.0-RELEASE',             # release
        b'QilingOS 99.0-RELEASE r1', # version
        machine,                     # machine
        b''                          # domainname
    )

    for i, f in enumerate(fields):
        ql.mem.write(buf + i * UTSLEN, f.ljust(UTSLEN, b'\x00'))

    return 0
