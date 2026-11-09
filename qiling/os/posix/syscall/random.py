#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.os.posix.const_mapping import get_errno_class

def ql_syscall_getrandom(ql: Qiling, buf: int, buflen: int, flags: int):
    if not ql.mem.is_mapped(buf, buflen):
        return -get_errno_class(ql.arch.type, ql.os.type).EFAULT.value

    data = os.urandom(buflen)
    ql.mem.write(buf, data)

    ql.log.debug(f'getrandom() CONTENT: {data.hex(" ")}')

    return len(data)
