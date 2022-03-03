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

    if in_fd not in range(NR_OPEN) or out_fd not in range(NR_OPEN):
        return -1

    ifile = ql.os.fd[in_fd]
    ofile = ql.os.fd[out_fd]

    if ifile is None or ofile is None:
        return -1

    ifile_pos = ifile.tell()
    offset = ql.mem.read_ptr(offset) if offset else ifile_pos

    ifile.lseek(offset)
    buf = ifile.read(count)

    if offset:
        current_offset = ifile.tell()
        ql.mem.write_ptr(offset, current_offset)
        ifile.lseek(ifile_pos)

    return ofile.write(buf)
