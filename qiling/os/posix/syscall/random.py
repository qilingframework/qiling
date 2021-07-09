#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os


from qiling.const import *


def ql_syscall_getrandom(ql, buf, buflen, flags, *args, **kw):
    data = None
    regreturn = None
    try:
        data = os.urandom(buflen)
        ql.mem.write(buf, data)
        regreturn = len(data)
    except:
        regreturn = -1

    if data:
        ql.log.debug("getrandom() CONTENT:")
        ql.log.debug(str(data))
    return regreturn
