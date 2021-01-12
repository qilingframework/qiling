#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import logging
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
    logging.info("writev(0x%x, 0x%x, 0x%x)" % (writev_fd, writev_vec, writev_vien))
    logging.debug("[+] writev() CONTENT:")
    for i in range(writev_vien):
        addr = ql.unpack(iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len])
        l = ql.unpack(iov[i * size_t_len * 2 + size_t_len : i * size_t_len * 2 + size_t_len * 2])
        regreturn += l
        logging.debug("%s" % str(ql.mem.read(addr, l)))
    return regreturn
