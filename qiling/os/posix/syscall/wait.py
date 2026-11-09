#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.os.posix.const_mapping import get_errno_class

def ql_syscall_wait4(ql: Qiling, pid: int, wstatus: int, options: int, rusage: int):
    pid = ql.os.utils.as_signed(pid, 32)
    options = ql.os.utils.as_signed(options, 32)

    try:
        spid, status, _ = os.wait4(pid, options)
    except ChildProcessError:
        return -get_errno_class(ql.arch.type, ql.os.type).ECHILD.value

    if wstatus:
        ql.mem.write_ptr(wstatus, status, 4)

    return spid
