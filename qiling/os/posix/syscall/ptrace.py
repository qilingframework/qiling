#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_ptrace(ql: Qiling, request: int, pid: int, addr: int, data: int):
    return 0
