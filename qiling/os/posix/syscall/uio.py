#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import TYPE_CHECKING, Iterator, Tuple

from qiling.os.posix.structs import make_iovec


if TYPE_CHECKING:
    from qiling import Qiling


def __iter_iovec_array(ql: Qiling, base: int, count: int) -> Iterator[Tuple[int, int]]:
    """Iterate over an iovec array, yielding one iovec's fields at a time.
    """

    iovec = make_iovec(ql.arch.bits, ql.arch.endian)

    for i in range(count):
        obj = iovec.load_from(ql.mem, base + i * iovec.sizeof())

        yield (obj.iov_base, obj.iov_len)


def ql_syscall_writev(ql: Qiling, fd: int, iov: int, iovcnt: int):
    ret = 0

    if hasattr(ql.os.fd[fd], 'write'):
        ql.log.debug('writev CONTENT:')

        for iov_base, iov_len in __iter_iovec_array(ql, iov, iovcnt):
            data = ql.mem.read(iov_base, iov_len)
            ql.log.debug(f'  {iov_base = :#x}, {iov_len = :#x} : {bytes(data)}')

            ql.os.fd[fd].write(data)
            ret += len(data)

    else:
        ql.log.debug('writev: destination fd is not writeable, no bytes were written')

    return ret


def ql_syscall_readv(ql: Qiling, fd: int, iov: int, iovcnt: int):
    ret = 0

    if hasattr(ql.os.fd[fd], 'read'):
        ql.log.debug('readv CONTENT:')

        for iov_base, iov_len in __iter_iovec_array(ql, iov, iovcnt):
            data = ql.os.fd[fd].read(iov_len)
            ql.log.debug(f'  {iov_base = :#x}, {iov_len = :#x} : {bytes(data)}')

            ql.mem.write(iov_base, data)
            ret += len(data)

    else:
        ql.log.debug('readv: source fd is not readable, no bytes were read')

    return ret
