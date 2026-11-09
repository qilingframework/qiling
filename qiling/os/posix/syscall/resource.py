#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

try:
    import resource
except ImportError:
    # The library 'resource' does not exist on windows, so provide a dummy shim
    class DummyResource:
        RLIM_INFINITY = -1

        def getrlimit(self, resource):
            return (-1, -1)
        def setrlimit(self, resource, rlim):
            pass
    resource = DummyResource()

import os

from unicorn import UcError

from qiling import Qiling
from qiling.os.posix.const_mapping import ql_errno_mapping, get_errno_class

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
    errno_class = get_errno_class(ql.arch.type, ql.os.type)

    # setrlimit() and getrlimit()
    if pid == 0 and new_limit == 0:
        try:
            rlim = resource.getrlimit(res)
        except (ValueError, OverflowError):
            return -errno_class.EINVAL.value
        except OSError as ex:
            return -ql_errno_mapping(ql, ex.errno)

        # struct rlimit64 holds two 64-bit fields; the guest expects all ones for unlimited
        rlim = [-1 if v == resource.RLIM_INFINITY else v for v in rlim]

        try:
            ql.mem.write_ptr(old_limit + 0, rlim[0], 8, signed=True)
            ql.mem.write_ptr(old_limit + 8, rlim[1], 8, signed=True)
        except UcError:
            return -errno_class.EFAULT.value

        return 0

    # set other process which pid != 0
    return -1

def ql_syscall_getpriority(ql: Qiling, which: int, who: int):
    errno_class = get_errno_class(ql.arch.type, ql.os.type)

    # not available on all hosting platforms (e.g. Windows)
    if not hasattr(os, 'getpriority'):
        return -errno_class.EOPNOTSUPP.value

    try:
        regreturn = os.getpriority(which, who)
    except OverflowError:
        regreturn = -errno_class.EINVAL.value
    except OSError as ex:
        regreturn = -ql_errno_mapping(ql, ex.errno)

    return regreturn
