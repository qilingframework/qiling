#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_gettid(ql: Qiling):
    if ql.os.thread_management:
        th = ql.os.thread_management.cur_thread
        regreturn = th.id
    else:
        # thread_management is None only if it is a single-threaded process.
        # In single-threaded process, the thread ID is equal to the process ID
        # per Posix documentation.
        regreturn = ql.os.pid

    return regreturn
