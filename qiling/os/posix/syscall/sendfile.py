#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from typing import TYPE_CHECKING, IO, Optional
from qiling.os.posix.const import NR_OPEN
from qiling.os.posix.const_mapping import get_errno_class


if TYPE_CHECKING:
    from qiling import Qiling


def ql_syscall_sendfile64(ql: Qiling, out_fd: int, in_fd: int, offset: int, count: int):
    # https://linux.die.net/man/2/sendfile64
    return ql_syscall_sendfile(ql, out_fd, in_fd, offset, count)


def ql_syscall_sendfile(ql: Qiling, out_fd: int, in_fd: int, offset: int, count: int):
    # https://man7.org/linux/man-pages/man2/sendfile.2.html

    errno_class = get_errno_class(ql.arch.type, ql.os.type)

    if in_fd not in range(NR_OPEN) or out_fd not in range(NR_OPEN):
        return -errno_class.EBADF.value

    ifile: Optional[IO] = ql.os.fd[in_fd]
    ofile: Optional[IO] = ql.os.fd[out_fd]

    if ifile is None or ofile is None:
        return -errno_class.EBADF.value

    if offset:
        ifile_pos = ifile.tell()

        # read offset from memory and seek it
        goto = ql.mem.read_ptr(offset)
        ifile.seek(goto)

    buf = ifile.read(count)

    if offset:
        # write updated offset to memory
        where = ifile.tell()
        ql.mem.write_ptr(offset, where)

        # retain old location
        ifile.seek(ifile_pos)

    return ofile.write(buf)
