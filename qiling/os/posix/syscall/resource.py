#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import resource

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_ugetrlimit(ql, ugetrlimit_resource, ugetrlimit_rlim, *args, **kw):
    rlim = resource.getrlimit(ugetrlimit_resource)
    ql.mem.write(ugetrlimit_rlim, ql.pack32s(rlim[0]) + ql.pack32s(rlim[1]))
    regreturn = 0
    ql.nprint("ugetrlimit(%d, 0x%x) = %d" % (ugetrlimit_resource, ugetrlimit_rlim, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setrlimit(ql, setrlimit_resource, setrlimit_rlim, *args, **kw):
    # maybe we can nop the setrlimit
    tmp_rlim = (ql.unpack32s(ql.mem.read(setrlimit_rlim, 4)), ql.unpack32s(ql.mem.read(setrlimit_rlim + 4, 4)))
    resource.setrlimit(setrlimit_resource, tmp_rlim)

    regreturn = 0
    ql.nprint("setrlimit(%d, 0x%x) = %d" % (setrlimit_resource, setrlimit_rlim, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_prlimit64(ql, prlimit64_pid, prlimit64_resource, prlimit64_new_limit, prlimit64_old_limit, *args, **kw):
    # setrlimit() and getrlimit()
    if prlimit64_pid == 0 and prlimit64_new_limit == 0:
        rlim = resource.getrlimit(prlimit64_resource)
        ql.mem.write(prlimit64_old_limit, ql.packs(rlim[0]) + ql.packs(rlim[1]))
        regreturn = 0
    else:
        # set other process which pid != 0
       regreturn = -1
    ql.nprint("prlimit64(%d, %d, 0x%x, 0x%x) = %d" % (prlimit64_pid, prlimit64_resource, prlimit64_new_limit, prlimit64_old_limit, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getpriority(ql, getpriority_which, getpriority_who, null1, null2, null3, null4):
    base = os.getpriority(getpriority_which, getpriority_who)
    regreturn = base
    ql.nprint("getpriority(0x%x, 0x%x) = %d" % (getpriority_which, getpriority_who, regreturn))
    ql.os.definesyscall_return(regreturn)
