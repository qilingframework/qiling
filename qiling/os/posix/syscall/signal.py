#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_rt_sigaction(ql: Qiling, signum: int, act: int, oldact: int):
    if oldact:
        arr = ql.os.sigaction_act[signum] or [0] * 5
        data = b''.join(ql.pack32(key) for key in arr)

        ql.mem.write(oldact, data)

    if act:
        ql.os.sigaction_act[signum] = [ql.mem.read_ptr(act + 4 * i, 4) for i in range(5)]

    return 0


def ql_syscall_rt_sigprocmask(ql: Qiling, how: int, nset: int, oset: int, sigsetsize: int):
    # SIG_BLOCK = 0x0
    # SIG_UNBLOCK = 0x1

    return 0


def ql_syscall_signal(ql: Qiling, sig: int, sighandler: int):
    return 0
