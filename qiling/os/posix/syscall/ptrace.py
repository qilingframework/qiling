#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import logging
from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_ptrace(ql, request, pid, addr, data, *args, **kw):
    regreturn = 0
    logging.info("ptrace(0x%x, 0x%x, 0x%x, 0x%x) = %d" % (request, pid, addr, data, regreturn))
    ql.os.definesyscall_return(regreturn)
