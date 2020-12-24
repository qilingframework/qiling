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

def ql_syscall_arch_prctl(ql, ARCHX, ARCH_SET_FS, *args, **kw):
    FSMSR = 0xC0000100
    ql.reg.msr(FSMSR, ARCH_SET_FS)
    regreturn = 0
    logging.info("arch_prctl(0x%x) = %d" % (ARCH_SET_FS, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_prctl(ql, *args, **kw):
    regreturn = 0
    logging.info("prctl() = %d" % (regreturn))
    ql.os.definesyscall_return(regreturn)
