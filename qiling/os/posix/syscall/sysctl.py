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

def ql_syscall__sysctl(ql, sysctl_name, sysctl_namelen, sysctl_bytes_oldlenp, sysctl_size_oldlenp, sysctl_bytes_newlen, sysctl_size_newlen):
    # sysctl (name=0x7fffffffe3d8, namelen=2, oldp=0x7fffffffe3d4, oldlenp=0x7fffffffe3e0, newp=0x0, newlen=<optimized out>)
    regreturn = 0
    ql.nprint("_sysctl(0x%x) = %i" % (sysctl_name, regreturn))
    ql.os.definesyscall_return(regreturn)
