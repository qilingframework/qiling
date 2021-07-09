#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *


def ql_syscall_writev(ql, writev_fd, writev_vec, writev_vien, *args, **kw):
    regreturn = 0
    size_t_len = ql.pointersize
    iov = ql.mem.read(writev_vec, writev_vien * size_t_len * 2)
    ql.log.debug("writev() CONTENT:")

    for i in range(writev_vien):
        addr = ql.unpack(
            iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len]
        )
        l = ql.unpack(
            iov[
                i * size_t_len * 2
                + size_t_len : i * size_t_len * 2
                + size_t_len * 2
            ]
        )
        regreturn += l
        buf = ql.mem.read(addr, l)
        ql.log.debug(buf)

        if hasattr(ql.os.fd[writev_fd], "write"):
            ql.os.fd[writev_fd].write(buf)

    return regreturn


def ql_syscall_readv(ql, fd, vec, vlen, *args, **kw):
    regreturn = 0
    size_t_len = ql.pointersize
    iov = ql.mem.read(vec, vlen * size_t_len * 2)
    ql.log.debug("readv() CONTENT:")

    for i in range(vlen):
        addr = ql.unpack(
            iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len]
        )
        l = ql.unpack(
            iov[
                i * size_t_len * 2
                + size_t_len : i * size_t_len * 2
                + size_t_len * 2
            ]
        )
        regreturn += l
        if hasattr(ql.os.fd[fd], "read"):
            data = ql.os.fd[fd].read(l)
            ql.log.debug(data)
            ql.mem.write(addr, data)

    return regreturn
