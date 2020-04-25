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

def ql_syscall_sendfile64(ql, sendfile64_out_fd, sendfile64_in_fd, sendfile64_offest, sendfile64_count, *args, **kw):
    if sendfile64_out_fd >= 0 and sendfile64_out_fd < 256 and sendfile64_in_fd >= 0 and sendfile64_in_fd < 256:
        ql.os.file_des[sendfile64_in_fd].lseek(ql.unpack32(ql.mem.read(sendfile64_offest, 4)))
        buf = ql.os.file_des[sendfile64_in_fd].read(sendfile64_count)
        regreturn = ql.os.file_des[sendfile64_out_fd].write(buf)
    else:
        regreturn = -1

    ql.nprint("sendfile64(%d, %d, %x, %d) = %d" % (sendfile64_out_fd, sendfile64_in_fd, sendfile64_offest, sendfile64_count, regreturn))
    ql.os.definesyscall_return(regreturn)
