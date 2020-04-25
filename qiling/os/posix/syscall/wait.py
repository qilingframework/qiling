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
from qiling.utils import *

def ql_syscall_wait4(ql, wait4_pid, wait4_wstatus, wait4_options, wait4_rusage, *args, **kw):
    spid, status, rusage = os.wait4(wait4_pid, wait4_options)
    ql.mem.write(wait4_wstatus, ql.pack32(status))
    regreturn = spid
    ql.nprint("wait4(%d, %d) = %d"% (wait4_pid, wait4_options, regreturn))
    ql.os.definesyscall_return(regreturn)
