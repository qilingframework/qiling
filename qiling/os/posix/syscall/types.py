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

def ql_syscall_gettid(ql, *args, **kw):
    th = ql.os.thread_management.cur_thread
    regreturn = th.get_thread_id()
    ql.nprint("gettid() = %d" % regreturn)
    ql.os.definesyscall_return(regreturn)
