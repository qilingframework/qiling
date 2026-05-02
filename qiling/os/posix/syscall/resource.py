#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

try:
    import resource
except ImportError:
    # The library 'resource' does not exist on windows, so provide a dummy shim
    class DummyResource:
        def getrlimit(self, resource):
            return (-1, -1)
        def setrlimit(self, resource, rlim):
            pass
    resource = DummyResource()

import os

from qiling import Qiling

def __getrlimit_common(ql: Qiling, res: int, rlim: int) -> int:
    RLIMIT_STACK = 3

    if res == RLIMIT_STACK:
        stack_size = ql.os.profile.getint(f"OS{ql.arch.bits}", "stack_size")
        rlimit = (stack_size, -1)

    else:
        rlimit = resource.getrlimit(res)

    ql.mem.write_ptr(rlim + 0 * ql.arch.pointersize, rlimit[0], signed=True)
    ql.mem.write_ptr(rlim + 1 * ql.arch.pointersize, rlimit[1], signed=True)

    return 0

def ql_syscall_ugetrlimit(ql: Qiling, res: int, rlim: int):
    return __getrlimit_common(ql, res, rlim)

def ql_syscall_getrlimit(ql: Qiling, res: int, rlim: int):
    return __getrlimit_common(ql, res, rlim)

def ql_syscall_setrlimit(ql: Qiling, res: int, rlim: int):
    # maybe we can nop the setrlimit
    tmp_rlim = (
        ql.mem.read_ptr(rlim + 0 * 4, 4, signed=True),
        ql.mem.read_ptr(rlim + 1 * 4, 4, signed=True)
    )

    resource.setrlimit(res, tmp_rlim)

    return 0

def ql_syscall_prlimit64(ql: Qiling, pid: int, res: int, new_limit: int, old_limit: int):
    # setrlimit() and getrlimit()
    if pid == 0 and new_limit == 0:
        try:
            rlim = resource.getrlimit(res)

            ql.mem.write_ptr(old_limit + 0 * ql.arch.pointersize, rlim[0], signed=True)
            ql.mem.write_ptr(old_limit + 1 * ql.arch.pointersize, rlim[1], signed=True)

            return 0
        except:
            return -1

    # set other process which pid != 0
    return -1

def ql_syscall_getpriority(ql: Qiling, which: int, who: int):
    try:
        regreturn = os.getpriority(which, who)
    except:
        regreturn = -1
    return regreturn
