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
    rlimit = resource.getrlimit(res)
    ql.mem.write(rlim, ql.pack32s(rlimit[0]) + ql.pack32s(rlimit[1]))

    return 0

def ql_syscall_ugetrlimit(ql: Qiling, res: int, rlim: int):
    return __getrlimit_common(ql, res, rlim)

def ql_syscall_getrlimit(ql: Qiling, res: int, rlim: int):
    return __getrlimit_common(ql, res, rlim)

def ql_syscall_setrlimit(ql: Qiling, setrlimit_resource: int, setrlimit_rlim: int):
    # maybe we can nop the setrlimit
    tmp_rlim = (ql.unpack32s(ql.mem.read(setrlimit_rlim, 4)), ql.unpack32s(ql.mem.read(setrlimit_rlim + 4, 4)))
    resource.setrlimit(setrlimit_resource, tmp_rlim)

    return 0

def ql_syscall_prlimit64(ql: Qiling, pid: int, res: int, new_limit: int, old_limit: int):
    # setrlimit() and getrlimit()
    if pid == 0 and new_limit == 0:
        rlim = resource.getrlimit(res)
        ql.mem.write(old_limit, ql.packs(rlim[0]) + ql.packs(rlim[1]))

        return 0

    # set other process which pid != 0
    return -1

def ql_syscall_getpriority(ql: Qiling, getpriority_which: int, getpriority_who: int):
    return os.getpriority(getpriority_which, getpriority_who)
