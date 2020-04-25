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

def ql_syscall_writev(ql, writev_fd, writev_vec, writev_vien, *args, **kw):
    regreturn = 0
    size_t_len = ql.archbit // 8
    iov = ql.mem.read(writev_vec, writev_vien * size_t_len * 2)
    ql.nprint("writev(0x%x, 0x%x, 0x%x)" % (writev_fd, writev_vec, writev_vien))
    if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
        ql.dprint(D_INFO, "[+] writev() CONTENT:")
        for i in range(writev_vien):
            addr = ql.unpack(iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len])
            l = ql.unpack(iov[i * size_t_len * 2 + size_t_len : i * size_t_len * 2 + size_t_len * 2])
            ql.dprint(D_INFO, "%s" % str(ql.mem.read(addr, l)))
    ql.os.definesyscall_return(regreturn)
