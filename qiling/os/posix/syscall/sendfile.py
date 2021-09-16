#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.posix.const import NR_OPEN

def ql_syscall_sendfile64(ql: Qiling, out_fd: int, in_fd: int, offest: int, count: int):
    if (0 <= out_fd < NR_OPEN and ql.os.fd[out_fd] != 0) and (0 <= in_fd < NR_OPEN and ql.os.fd[in_fd] != 0):
        ql.os.fd[in_fd].lseek(ql.unpack32(ql.mem.read(offest, 4)))
        buf = ql.os.fd[in_fd].read(count)
        regreturn = ql.os.fd[out_fd].write(buf)
    else:
        regreturn = -1

    return regreturn
