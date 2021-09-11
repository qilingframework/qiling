#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_poll(ql: Qiling, fds: int, nfds: int, timeout: int):
    return 0