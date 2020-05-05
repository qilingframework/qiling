#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_rt_sigaction(ql, rt_sigaction_signum, rt_sigaction_act, rt_sigaction_oldact, *args, **kw):
    if rt_sigaction_oldact != 0:
        if ql.os.sigaction_act[rt_sigaction_signum] == 0:
            ql.mem.write(rt_sigaction_oldact, b'\x00' * 20)
        else:
            data = b''
            for key in ql.os.sigaction_act[rt_sigaction_signum]:
                data += ql.pack32(key)
            ql.mem.write(rt_sigaction_oldact, data)

    if rt_sigaction_act != 0:
        data = []
        for key in range(5):
            data.append(ql.unpack32(ql.mem.read(rt_sigaction_act + 4 * key, 4)))
        ql.os.sigaction_act[rt_sigaction_signum] = data

    regreturn = 0
    ql.nprint("rt_sigaction(0x%x, 0x%x, = 0x%x) = %d" % (rt_sigaction_signum, rt_sigaction_act, rt_sigaction_oldact, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_rt_sigprocmask(ql, rt_sigprocmask_how, rt_sigprocmask_nset, rt_sigprocmask_oset, rt_sigprocmask_sigsetsize, *args, **kw):
    SIG_BLOCK = 0x0
    SIG_UNBLOCK = 0x1

    if rt_sigprocmask_how == SIG_BLOCK:
        pass

    regreturn = 0
    ql.nprint("rt_sigprocmask(0x%x, 0x%x, 0x%x, 0x%x) = %d" % (rt_sigprocmask_how, rt_sigprocmask_nset, rt_sigprocmask_oset, rt_sigprocmask_sigsetsize, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_signal(ql, sig, __sighandler_t, *args, **kw):
    regreturn = 0
    ql.nprint("signal(%d, 0x%x) = %d" % (sig, __sighandler_t,regreturn))
    ql.os.definesyscall_return(regreturn)
