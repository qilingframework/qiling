#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_rt_sigaction(ql: Qiling, signum: int, act: int, oldact: int):
    if oldact:
        if ql.os.sigaction_act[signum] == 0:
            data = b'\x00' * 20
        else:
            data = b''.join(ql.pack32(key) for key in ql.os.sigaction_act[signum])

        ql.mem.write(oldact, data)

    if act:
        ql.os.sigaction_act[signum] = [ql.unpack32(ql.mem.read(act + 4 * key, 4)) for key in range(5)]

    return 0


def ql_syscall_rt_sigprocmask(ql: Qiling, how: int, nset: int, oset: int, sigsetsize: int):
    # SIG_BLOCK = 0x0
    # SIG_UNBLOCK = 0x1

    return 0


def ql_syscall_signal(ql: Qiling, sig: int, sighandler: int):
    return 0
