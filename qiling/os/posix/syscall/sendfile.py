#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.posix.const import NR_OPEN


def ql_syscall_sendfile64(ql: Qiling, out_fd: int, in_fd: int, offset: int, count: int):
    # https://linux.die.net/man/2/sendfile64
    return ql_syscall_sendfile(ql, out_fd, in_fd, offset, count)


def ql_syscall_sendfile(ql: Qiling, out_fd: int, in_fd: int, offset: int, count: int):
    # https://man7.org/linux/man-pages/man2/sendfile.2.html
    if 0 <= out_fd < NR_OPEN and 0 <= in_fd < NR_OPEN \
            and ql.os.fd[out_fd] != 0 and ql.os.fd[in_fd] != 0:

        in_fd_pos = ql.os.fd[in_fd].tell()
        if offset:
            # Handle sendfile64 and sendfile offset_ptr
            offset = ql.unpack(ql.mem.read(offset, ql.pointersize))
        else:
            offset = in_fd_pos

        ql.os.fd[in_fd].lseek(offset)
        buf = ql.os.fd[in_fd].read(count)
        if offset:
            current_offset = ql.os.fd[in_fd].tell()
            ql.mem.write(offset, ql.pack(current_offset))
            ql.os.fd[in_fd].lseek(in_fd_pos)

        regreturn = ql.os.fd[out_fd].write(buf)

    else:
        regreturn = -1

    return regreturn
