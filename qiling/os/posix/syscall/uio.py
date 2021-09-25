#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_writev(ql: Qiling, fd: int, vec: int, vlen: int):
    regreturn = 0
    size_t_len = ql.pointersize
    iov = ql.mem.read(vec, vlen * size_t_len * 2)
    ql.log.debug('writev() CONTENT:')

    for i in range(vlen):
        addr = ql.unpack(iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len])
        l = ql.unpack(iov[i * size_t_len * 2 + size_t_len : i * size_t_len * 2 + size_t_len * 2])
        regreturn += l

        buf = ql.mem.read(addr, l)
        ql.log.debug(f'{buf.decode()!r}')

        if hasattr(ql.os.fd[fd], 'write'):
            ql.os.fd[fd].write(buf)

    return regreturn


def ql_syscall_readv(ql: Qiling, fd: int, vec: int, vlen: int):
    regreturn = 0
    size_t_len = ql.pointersize
    iov = ql.mem.read(vec, vlen * size_t_len * 2)
    ql.log.debug('readv() CONTENT:')

    for i in range(vlen):
        addr = ql.unpack(iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len])
        l = ql.unpack(iov[i * size_t_len * 2 + size_t_len : i * size_t_len * 2 + size_t_len * 2])
        regreturn += l

        if hasattr(ql.os.fd[fd], 'read'):
            data = ql.os.fd[fd].read(l)
            ql.log.debug(f'{data!r}')
            ql.mem.write(addr, data)

    return regreturn
