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
    if ql.os.thread_management:
      th = ql.os.thread_management.cur_thread
      regreturn = th.get_thread_id()
    else:
      # thread_management is None only if it is a single-threaded process.
      # In single-threaded process, the thread ID is equal to the process ID
      # per Posix documentation.
      regreturn = ql.os.pid
    ql.nprint("gettid() = %d" % regreturn)
    ql.os.definesyscall_return(regreturn)
