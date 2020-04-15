#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_sysinfo(ql, sysinfo_info, *args, **kw):

    data = b''
    data += struct.pack("QQQQQQQQQQHQQI",
                       0x1234, # uptime
                       0x2000, # loads (1 min)
                       0x2000, # loads (5 min)
                       0x2000, # loads (15 min)
                       0x10000000, # total ram
                       0x10000000, # free ram
                       0x10000000, # shared memory
                       0x0, # memory used by buffers
                       0x0, # total swap
                       0x0, # free swap
                       0x1, # nb current processes
                       0x0, # total high mem
                       0x0, # available high mem
                       0x1, # memory unit size
    )

    regreturn = 0
    ql.nprint("sysinfo(0x%x) = %d" % (sysinfo_info, regreturn))
    #ql.mem.write(sysinfo_info, data)
    ql.os.definesyscall_return(regreturn)
